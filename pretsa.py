from anytree import AnyNode, PreOrderIter
from levenshtein import levenshtein
import sys
from scipy.stats import wasserstein_distance
from scipy.stats import normaltest
import pandas as pd
import numpy as np
import time
import hashlib
import uuid

class Pretsa:
    def __init__(self, current_log, previous_logs=None):
        self.current_log = current_log
        self.previous_logs = previous_logs

        # Define standard column names
        self.__caseIDColName = "Case ID"
        self.__activityColName = "Activity"
        self.__annotationColName = "Duration"
        self.__constantEventNr = "Event_Nr"
        
        # Check if Participant_ID column exists in the input log
        self.__participantIDColName = "Participant_ID" if "Participant_ID" in current_log.columns else None
        self.__caseToParticipantDict = {}  # Will store case ID to participant ID mapping
        
        # Rest of initialization code...
        root = AnyNode(id='Root', name="Root", cases=set(), sequence="", annotation=dict(),sequences=set())
        current = root
        currentCase = ""
        caseToSequenceDict = dict()
        sequence = None
        self.__annotationDataOverAll = dict()
        self.__normaltest_alpha = 0.05
        self.__normaltest_result_storage = dict()
        self.__normalTCloseness = True
        
        # Track all traces seen in previous logs
        if self.previous_logs:
            print("Extracting previous traces...")
            self.__previous_traces = set()
            self.__extract_previous_traces()
        
        # Process current log
        for index, row in current_log.iterrows():
            activity = row[self.__activityColName]
            annotation = row[self.__annotationColName]
            if row[self.__caseIDColName] != currentCase:
                current = root
                if not sequence is None:
                    caseToSequenceDict[currentCase] = sequence
                    current.sequences.add(sequence)
                currentCase = row[self.__caseIDColName]
                current.cases.add(currentCase)
                sequence = ""
                
                # Store the participant ID for this case if it exists
                if self.__participantIDColName and self.__participantIDColName in row:
                    self.__caseToParticipantDict[currentCase] = row[self.__participantIDColName]
                    
            childAlreadyExists = False
            sequence = sequence + "@" + activity
            for child in current.children:
                if child.name == activity:
                    childAlreadyExists = True
                    current = child
            if not childAlreadyExists:
                node = AnyNode(id=index, name=activity, parent=current, cases=set(), sequence=sequence, annotations=dict())
                current = node
            current.cases.add(currentCase)
            current.annotations[currentCase] = annotation
            self.__addAnnotation(annotation, activity)
        if currentCase:  # Check if we processed any cases
            caseToSequenceDict[currentCase] = sequence
            root.sequences.add(sequence)
            
        self._tree = root
        self._caseToSequenceDict = caseToSequenceDict
        self.__numberOfTracesOriginal = len(self._tree.cases)
        self._sequentialPrunning = True
        self.__setMaxDifferences()
        self.__haveAllValuesInActivitityDistributionTheSameValue = dict()
        self._distanceMatrix = self.__generateDistanceMatrixSequences(self._getAllPotentialSequencesTree(self._tree))

    def __extract_previous_traces(self):
        """Extract all traces (sequences) from previous logs"""
        if not self.previous_logs:
            return
            
        for prev_log in self.previous_logs:         # Iterate over all previous logs
            print(f"Processing previous log with {len(prev_log)} events...")
            sequences = set()
            current_case = None
            current_sequence = ""
            
            for _, row in prev_log.iterrows():      # Iterate over all rows in that log
                case_id = row[self.__caseIDColName]
                activity = row[self.__activityColName]
                
                if case_id != current_case:         # New case
                    if current_case is not None and current_sequence:   
                        sequences.add(current_sequence)     
                    current_case = case_id
                    current_sequence = ""
                
                current_sequence = current_sequence + "@" + activity    # Append activity to sequence
            
            # Add the last sequence
            if current_sequence:
                sequences.add(current_sequence)
                
            self.__previous_traces.update(sequences)

    def set_privacy_parameters(self, epsilon=1.0, delta=0.0):      # Sets the privacy parameters
        """Set differential privacy parameters"""
        self.__epsilon = epsilon

    def __addAnnotation(self, annotation, activity):
        dataForActivity = self.__annotationDataOverAll.get(activity, None)
        if dataForActivity is None:
            self.__annotationDataOverAll[activity] = []
            dataForActivity = self.__annotationDataOverAll[activity]
        dataForActivity.append(annotation)

    def __setMaxDifferences(self):
        self.annotationMaxDifferences = dict()
        for key in self.__annotationDataOverAll.keys():
            maxVal = max(self.__annotationDataOverAll[key])
            minVal = min(self.__annotationDataOverAll[key])
            self.annotationMaxDifferences[key] = abs(maxVal - minVal)

    def _violatesTCloseness(self, activity, annotations, t, cases):
        distributionActivity = self.__annotationDataOverAll[activity]
        maxDifference = self.annotationMaxDifferences[activity]
        #Consider only data from cases still in node
        distributionEquivalenceClass = []
        casesInClass = cases.intersection(set(annotations.keys()))
        for caseInClass in casesInClass:
            distributionEquivalenceClass.append(annotations[caseInClass])
        if len(distributionEquivalenceClass) == 0: #No original annotation is left in the node
            return False
        if maxDifference == 0.0: #All annotations have the same value(most likely= 0.0)
            return
        if self.__normalTCloseness == True:
            return ((wasserstein_distance(distributionActivity,distributionEquivalenceClass)/maxDifference) >= t)
        else:
            return self._violatesStochasticTCloseness(distributionActivity,distributionEquivalenceClass,t,activity)

    def _treePrunning(self, k,t):
        cutOutTraces = set()
        for node in PreOrderIter(self._tree):
            if node != self._tree:
                node.cases = node.cases.difference(cutOutTraces)
                if len(node.cases) < k or self._violatesTCloseness(node.name, node.annotations, t, node.cases):
                    cutOutTraces = cutOutTraces.union(node.cases)
                    self._cutCasesOutOfTreeStartingFromNode(node,cutOutTraces)
                    if self._sequentialPrunning:
                        return cutOutTraces
        return cutOutTraces

    def _cutCasesOutOfTreeStartingFromNode(self,node,cutOutTraces,tree=None):
        if tree == None:
            tree = self._tree
        current = node
        try:
            tree.sequences.remove(node.sequence)
        except KeyError:
            pass
        while current != tree:
            current.cases = current.cases.difference(cutOutTraces)
            if len(current.cases) == 0:
                node = current
                current = current.parent
                node.parent = None
            else:
                current = current.parent

    def _getAllPotentialSequencesTree(self, tree):
        return tree.sequences

    def _addCaseToTree(self, trace, sequence,tree=None):
        if tree == None:
            tree = self._tree
        if trace != "":
            activities = sequence.split("@")
            currentNode = tree
            tree.cases.add(trace)
            for activity in activities:
                for child in currentNode.children:
                    if child.name == activity:
                        child.cases.add(trace)
                        currentNode = child
                        break

    def __combineTracesAndTree(self, traces):
        #We transform the set of sequences into a list and sort it, to discretize the behaviour of the algorithm
        sequencesTree = list(self._getAllPotentialSequencesTree(self._tree))
        sequencesTree.sort()
        for trace in traces:
            bestSequence = ""
            #initial value as high as possible
            lowestDistance = sys.maxsize
            traceSequence = self._caseToSequenceDict[trace]
            for treeSequence in sequencesTree:
                currentDistance = self._getDistanceSequences(traceSequence, treeSequence)
                if currentDistance < lowestDistance:
                    bestSequence = treeSequence
                    lowestDistance = currentDistance
            self._overallLogDistance += lowestDistance
            self._addCaseToTree(trace, bestSequence)

    def runPretsa(self, k, t, normalTCloseness=True, differentialPrivacy=False):
        # First run the original PRETSA algorithm
        self.__normalTCloseness = normalTCloseness
        if not self.__normalTCloseness:
            self.__haveAllValuesInActivitityDistributionTheSameValue = dict()
        self._overallLogDistance = 0.0
        if self._sequentialPrunning:
            cutOutCases = set()
            cutOutCase = self._treePrunning(k,t)
            while len(cutOutCase) > 0:
                self.__combineTracesAndTree(cutOutCase)
                cutOutCases = cutOutCases.union(cutOutCase)
                cutOutCase = self._treePrunning(k,t)
        else:
            cutOutCases = self._treePrunning(k,t)
            self.__combineTracesAndTree(cutOutCases)
            
        if differentialPrivacy:     # If differential privacy is enabled apply it
            self.__apply_differential_privacy(self.__epsilon)
            
        return cutOutCases, self._overallLogDistance
        
    def __apply_differential_privacy(self, epsilon):
        """Apply differential privacy to the sanitized event log using Laplace mechanism."""
        print(f"Applying differential privacy with epsilon of {epsilon}")
        
        if epsilon <= 0 or not self.previous_logs:
            print("Invalid epsilon value or no previous logs provided. Skipping differential privacy.")
            return

        # Applies DP to the sequence patterns
        sequences_to_remove = set()
        removed_case_ids = []  # Track removed case IDs
        
        # Extracts activity sequences from previous logs for matching
        prev_activity_sequences = set()
        for seq in self.__previous_traces:
            activities = [a.split(':')[0] if ':' in a else a for a in seq.split('@')[1:]]
            prev_activity_sequences.add('-'.join(activities))
        
        # 1. Process existing sequences
        print("There are", len(self._tree.sequences), "sequences")
        matches_found = 0
        
        for sequence in list(self._tree.sequences):
            cases_with_sequence = {case for case in self._tree.cases if self._caseToSequenceDict.get(case) == sequence}
            sequence_count = len(cases_with_sequence)
            
            # Extracts the activities from the current sequence
            cur_activities = [a.split(':')[0] if ':' in a else a for a in sequence.split('@')[1:]]
            cur_activity_seq = '-'.join(cur_activities)
            
            # Checks if this activity sequence exists in previous logs
            found_match = False
            for prev_seq in prev_activity_sequences:
                if cur_activity_seq == prev_seq or cur_activity_seq in prev_seq or prev_seq in cur_activity_seq:
                    found_match = True
                    matches_found += 1
                    break
                    
            if found_match:         # If this sequence exists in previous logs, it's a linkage risk so add Laplace noise
                noisy_count = max(0, sequence_count + int(np.random.laplace(0, 1/epsilon)))
                
                if noisy_count < sequence_count:            # If noisy count is significantly different, adjust the sequence
                    cases_to_remove = np.random.choice(
                        list(cases_with_sequence), 
                        size=min(sequence_count - noisy_count, sequence_count), 
                        replace=False
                    ) 
                    for case in cases_to_remove:
                        sequences_to_remove.add((case, sequence))
                        removed_case_ids.append(case)
        
        print(f"Found {matches_found} sequences matching between current and previous logs")
        
        # 2. Apply removals
        for case, sequence in sequences_to_remove:
            for node in PreOrderIter(self._tree):
                if node != self._tree and case in node.cases:
                    node.cases.remove(case)
                    if case in node.annotations:
                        del node.annotations[case]

        # 3. Replace removed cases with synthetic cases
        print(f"Removed {len(sequences_to_remove)} cases and adding synthetic cases...")
        for i in range(len(sequences_to_remove)):
            case_id = removed_case_ids[i]
            if self._tree.sequences:
                sequence = np.random.choice(list(self._tree.sequences))
                
                if self.__participantIDColName and case_id in self.__caseToParticipantDict:     # Preserve the participant ID when creating a synthetic case (for mpc_pretsa)
                    self.__caseToParticipantDict[case_id] = self.__caseToParticipantDict[case_id]
                
                # Add case to the tree with the new sequence
                self._addCaseToTree(case_id, sequence)
                self._caseToSequenceDict[case_id] = sequence
                
                # Generates synthetic durations for each activity in the sequence
                activities = sequence.split('@')[1:]  # Skips empty first element
                for activity in activities:
                    synthetic_duration = round(self.__generateNewAnnotation(activity))
                    for node in PreOrderIter(self._tree):
                        if node.name == activity and case_id in node.cases:
                            node.annotations[case_id] = synthetic_duration
                            break

    def __generateNewAnnotation(self, activity):
        #normaltest works only with more than 8 samples
        if(len(self.__annotationDataOverAll[activity])) >=8 and activity not in self.__normaltest_result_storage.keys():
            stat, p = normaltest(self.__annotationDataOverAll[activity])
        else:
            p = 1.0
        self.__normaltest_result_storage[activity] = p
        if self.__normaltest_result_storage[activity] <= self.__normaltest_alpha:
            mean = np.mean(self.__annotationDataOverAll[activity])
            std = np.std(self.__annotationDataOverAll[activity])
            randomValue = np.random.normal(mean, std)
        else:
            randomValue = np.random.choice(self.__annotationDataOverAll[activity])
        if randomValue < 0:
            randomValue = 0
        return randomValue

    def getEvent(self,case,node):
        event = {
            self.__activityColName: node.name,
            self.__caseIDColName: case,
            self.__annotationColName: node.annotations.get(case, self.__generateNewAnnotation(node.name)),
            self.__constantEventNr: node.depth
        }
        
        # Add Participant_ID if it was in the original log
        if self.__participantIDColName and case in self.__caseToParticipantDict:
            event[self.__participantIDColName] = self.__caseToParticipantDict[case]
            
        return event

    def getEventsOfNode(self, node):
        events = []
        if node != self._tree:
            events = events + [self.getEvent(case, node) for case in node.cases]
        return events

    def getPrivatisedEventLog(self):
        events = []
        self.__normaltest_result_storage = dict()
        nodeEvents = [self.getEventsOfNode(node) for node in PreOrderIter(self._tree)]
        for node in nodeEvents:
            events.extend(node)
        eventLog = pd.DataFrame(events)
        if not eventLog.empty:
            eventLog = eventLog.sort_values(by=[self.__caseIDColName, self.__constantEventNr])
        return eventLog


    def __generateDistanceMatrixSequences(self,sequences):
        distanceMatrix = dict()
        for sequence1 in sequences:
            distanceMatrix[sequence1] = dict()
            for sequence2 in sequences:
                if sequence1 != sequence2:
                    distanceMatrix[sequence1][sequence2] = levenshtein(sequence1,sequence2)
        print("Generated Distance Matrix")
        return distanceMatrix

    def _getDistanceSequences(self, sequence1, sequence2):
        if sequence1 == "" or sequence2 == "" or sequence1 == sequence2:
            return sys.maxsize
        try:
            distance = self._distanceMatrix[sequence1][sequence2]
        except KeyError:
            print("A Sequence is not in the distance matrix")
            print(sequence1)
            print(sequence2)
            raise
        return distance

    def __areAllValuesInDistributionAreTheSame(self, distribution):
        if max(distribution) == min(distribution):
            return True
        else:
            return False

    def _violatesStochasticTCloseness(self,distributionEquivalenceClass,overallDistribution,t,activity):
        if activity not in self.__haveAllValuesInActivitityDistributionTheSameValue.keys():
            self.__haveAllValuesInActivitityDistributionTheSameValue[activity] = self.__areAllValuesInDistributionAreTheSame(overallDistribution)
        if not self.__haveAllValuesInActivitityDistributionTheSameValue[activity]:
            upperLimitsBuckets = self._getBucketLimits(t,overallDistribution)
            return (self._calculateStochasticTCloseness(overallDistribution, distributionEquivalenceClass, upperLimitsBuckets) > t)
        else:
            return False

    def _calculateStochasticTCloseness(self, overallDistribution, equivalenceClassDistribution, upperLimitBuckets):
        overallDistribution.sort()
        equivalenceClassDistribution.sort()
        counterOverallDistribution = 0
        counterEquivalenceClass = 0
        distances = list()
        for bucket in upperLimitBuckets:
            lastCounterOverallDistribution = counterOverallDistribution
            lastCounterEquivalenceClass = counterEquivalenceClass
            while counterOverallDistribution<len(overallDistribution) and overallDistribution[counterOverallDistribution
            ] < bucket:
                counterOverallDistribution = counterOverallDistribution + 1
            while counterEquivalenceClass<len(equivalenceClassDistribution) and equivalenceClassDistribution[counterEquivalenceClass
            ] < bucket:
                counterEquivalenceClass = counterEquivalenceClass + 1
            probabilityOfBucketInEQ = (counterEquivalenceClass-lastCounterEquivalenceClass)/len(equivalenceClassDistribution)
            probabilityOfBucketInOverallDistribution = (counterOverallDistribution-lastCounterOverallDistribution)/len(overallDistribution)
            if probabilityOfBucketInEQ == 0 and probabilityOfBucketInOverallDistribution == 0:
                distances.append(0)
            elif probabilityOfBucketInOverallDistribution == 0 or probabilityOfBucketInEQ == 0:
                distances.append(sys.maxsize)
            else:
                distances.append(max(probabilityOfBucketInEQ/probabilityOfBucketInOverallDistribution,probabilityOfBucketInOverallDistribution/probabilityOfBucketInEQ))
        return max(distances)



    def _getBucketLimits(self,t,overallDistribution):
        numberOfBuckets = round(t+1)
        overallDistribution.sort()
        divider = round(len(overallDistribution)/numberOfBuckets)
        upperLimitsBuckets = list()
        for i in range(1,numberOfBuckets):
            upperLimitsBuckets.append(overallDistribution[min(round(i*divider),len(overallDistribution)-1)])
        return upperLimitsBuckets